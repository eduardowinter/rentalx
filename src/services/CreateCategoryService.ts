

interface IRequest {
  name: string;
  description: string;
}

class CreateCategoryService {
  execute({ name, description }: IRequest) {
    const categoryAlreadyExists = categoriesRepository.findByName(name);

    if (categoryAlreadyExists) {
      return response.status(400).json({error: "Category already exists!" })
    }

    categoriesRepository.create({name, description});
  }
}
  
export { CreateCategoryService }